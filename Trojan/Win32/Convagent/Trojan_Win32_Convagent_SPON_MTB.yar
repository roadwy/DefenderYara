
rule Trojan_Win32_Convagent_SPON_MTB{
	meta:
		description = "Trojan:Win32/Convagent.SPON!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 45 f8 50 89 75 f8 e8 ?? ?? ?? ?? 8a 45 f8 30 04 3b 83 7d 08 0f 59 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}