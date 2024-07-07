
rule Trojan_Win32_Lokibot_SMC_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.SMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_00_0 = {5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 } //1 \Borland\Delphi
		$a_02_1 = {88 0a 83 c0 90 0a 20 00 8a 90 90 90 01 03 00 80 f2 90 01 01 88 15 90 01 01 90 01 03 8b 15 90 01 01 90 1b 04 8a 0d 90 01 01 90 1b 04 90 00 } //3
		$a_02_2 = {83 f8 07 75 90 01 01 6a 01 e8 90 01 01 90 01 03 25 00 ff 00 00 3d 00 0d 00 00 74 90 01 01 3d 00 04 00 00 75 90 0a 37 00 6a 00 e8 90 01 01 90 1b 02 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*3+(#a_02_2  & 1)*1) >=5
 
}