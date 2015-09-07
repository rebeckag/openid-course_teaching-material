<%inherit file="base.html"/>

<%block name="head_title">
    Unauthorized: ${parent.head_title()}
</%block>

<div class="row" style="text-align: center">
    <div class="col-lg-12">${message}</div>
</div>