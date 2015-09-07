<%inherit file="base.html"/>

<%block name="head_title">
    Login: ${parent.head_title()}
</%block>

<div class="header">
    <h1><a href="/">${title}</a></h1>
</div>

<div class="login_form" class="block">
    <form action="${action}" method="post" class="login form">
        <input type="hidden" name="query" value="${query}"/>
        <input type="hidden" name="acr_values" value="${acr}"/>
        <table>
            <tr>
                <td>${login_title}</td>
                <td><input type="text" name="login" value="${login}" autofocus>
                </td>
            </tr>
            <tr>
                <td>${passwd_title}</td>
                <td><input type="password" name="password"
                           value="${password}"/></td>
            </tr>
            <tr>
                </td>
                <td><input type="submit" name="form.commit"
                           value="${submit_text}"></td>
            </tr>
        </table>
    </form>
</div>