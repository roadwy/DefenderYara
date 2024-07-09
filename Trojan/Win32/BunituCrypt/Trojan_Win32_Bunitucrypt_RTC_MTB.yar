
rule Trojan_Win32_Bunitucrypt_RTC_MTB{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RTC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 02 33 c0 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 } //1
		$a_03_1 = {2d 00 10 00 00 [0-0a] 83 [0-05] 04 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}