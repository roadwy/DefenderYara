
rule Trojan_Win32_Obfuscator_EM_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.EM!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 07 0f b6 cb 03 c1 99 8b ce f7 f9 8b 45 f0 83 4d fc ff 8a 4c 15 00 30 08 40 8d 8d c0 fe ff ff 89 45 f0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}