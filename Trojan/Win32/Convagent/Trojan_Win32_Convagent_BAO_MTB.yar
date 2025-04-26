
rule Trojan_Win32_Convagent_BAO_MTB{
	meta:
		description = "Trojan:Win32/Convagent.BAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {50 89 bd f8 f7 ff ff e8 ?? ?? ?? ?? 8b 85 f4 f7 ff ff 59 8a 8d f8 f7 ff ff 03 c6 30 08 83 fb 0f 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}