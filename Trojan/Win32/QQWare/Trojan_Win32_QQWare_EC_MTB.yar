
rule Trojan_Win32_QQWare_EC_MTB{
	meta:
		description = "Trojan:Win32/QQWare.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_81_0 = {79 62 74 6a 2e 31 38 39 2e 63 6e 3d 33 38 30 43 42 37 41 35 35 30 30 33 31 45 30 44 37 34 30 46 32 38 44 43 33 46 45 38 38 42 38 30 } //1 ybtj.189.cn=380CB7A550031E0D740F28DC3FE88B80
		$a_81_1 = {44 65 6c 65 74 65 55 72 6c 43 61 63 68 65 45 6e 74 72 79 41 } //1 DeleteUrlCacheEntryA
		$a_81_2 = {49 6e 74 65 72 6e 65 74 47 65 74 43 6f 6f 6b 69 65 41 } //1 InternetGetCookieA
		$a_81_3 = {40 69 66 72 61 6d 65 2e 69 70 31 33 38 2e 63 6f 6d 2f 69 63 2e 61 73 70 } //1 @iframe.ip138.com/ic.asp
		$a_81_4 = {69 70 2e 71 71 2e 63 6f 6d } //1 ip.qq.com
		$a_81_5 = {70 76 2e 73 6f 68 75 2e 63 6f 6d 2f 63 69 74 79 6a 73 6f 6e } //1 pv.sohu.com/cityjson
		$a_81_6 = {63 6f 75 6e 74 65 72 2e 73 69 6e 61 2e 63 6f 6d 2e 63 6e 2f 69 70 } //1 counter.sina.com.cn/ip
		$a_81_7 = {69 70 2e 74 61 6f 62 61 6f 2e 63 6f 6d 2f 73 65 72 76 69 63 65 2f 67 65 74 49 70 49 6e 66 6f 32 2e 70 68 70 3f 69 70 3d 6d 79 69 70 } //1 ip.taobao.com/service/getIpInfo2.php?ip=myip
		$a_81_8 = {77 77 77 2e 31 32 33 63 68 61 2e 63 6f 6d 2f 69 70 2f } //1 www.123cha.com/ip/
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=9
 
}