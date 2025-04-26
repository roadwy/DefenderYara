
rule Trojan_Win64_Lazy_GM_MTB{
	meta:
		description = "Trojan:Win64/Lazy.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 68 72 6f 6d 65 46 75 63 6b 4e 65 77 43 6f 6f 6b 69 65 73 } //2 ChromeFuckNewCookies
		$a_01_1 = {2f 63 20 74 69 6d 65 6f 75 74 20 2f 74 20 31 30 20 26 20 64 65 6c 20 2f 66 20 2f 71 } //2 /c timeout /t 10 & del /f /q
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}