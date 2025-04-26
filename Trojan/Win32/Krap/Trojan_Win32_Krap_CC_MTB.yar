
rule Trojan_Win32_Krap_CC_MTB{
	meta:
		description = "Trojan:Win32/Krap.CC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {80 30 60 60 61 80 30 72 53 31 db 5b 40 48 80 28 88 53 31 db 5b 80 30 f6 53 31 db 5b 80 00 95 90 80 28 7b 42 4a 80 00 40 43 4b 80 28 11 60 61 80 00 15 40 3d 78 ce 43 00 7e c2 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}