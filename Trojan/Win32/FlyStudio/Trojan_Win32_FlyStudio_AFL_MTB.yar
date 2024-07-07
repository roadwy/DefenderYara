
rule Trojan_Win32_FlyStudio_AFL_MTB{
	meta:
		description = "Trojan:Win32/FlyStudio.AFL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6a 00 6a 00 6a 00 ff 15 38 65 48 00 8b 4c 24 04 6a 01 6a 00 6a 00 51 68 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}