/* Copyright 2018--2020 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.exonerator;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ExoneraTorRedirectServlet extends HttpServlet {

  private static final long serialVersionUID = 526889516976914884L;

  @Override
  public void doGet(HttpServletRequest request, HttpServletResponse response) {
    String redirectUrl = "https://metrics.torproject.org/exonerator.html";
    if (null != request.getQueryString()) {
      redirectUrl += "?" + request.getQueryString();
    }
    response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY);
    response.setHeader("Location", redirectUrl);
  }
}

