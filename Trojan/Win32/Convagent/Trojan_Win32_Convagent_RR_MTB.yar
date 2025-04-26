
rule Trojan_Win32_Convagent_RR_MTB{
	meta:
		description = "Trojan:Win32/Convagent.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {50 8d 85 00 fc ff ff 50 6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 6a 00 8b 85 f8 fe ff ff 50 e8 } //1
		$a_03_1 = {50 8b 85 48 fc ff ff 50 e8 ?? ?? ?? ?? 83 f8 01 1b c0 40 88 85 f3 fe ff ff 8b 85 48 fc ff ff 50 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}