
rule Trojan_Win32_ReLineStealer_XV_MTB{
	meta:
		description = "Trojan:Win32/ReLineStealer.XV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {56 53 31 db 83 ec 90 01 01 8b 7d 90 01 01 3b 5d 90 01 01 90 01 02 89 d8 31 d2 8d 4d 90 01 01 f7 75 90 01 01 8b 45 90 01 01 0f be 34 10 e8 90 01 04 69 c6 90 01 04 30 04 1f 43 eb 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}