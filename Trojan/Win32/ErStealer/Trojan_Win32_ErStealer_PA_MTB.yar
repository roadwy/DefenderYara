
rule Trojan_Win32_ErStealer_PA_MTB{
	meta:
		description = "Trojan:Win32/ErStealer.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {b8 99 21 ed 7c f7 e1 c1 ea 19 0f be c2 6b c0 90 01 01 2c 30 02 c1 30 44 0d f8 41 83 f9 07 7c 90 00 } //10
		$a_03_1 = {55 8b ec a1 90 01 04 83 e0 1f 6a 20 59 2b c8 8b 45 08 d3 c8 33 05 90 00 } //1
		$a_03_2 = {8b c8 8b 1e 83 e1 90 01 01 8b 7e 90 01 01 33 d8 8b 76 90 01 01 33 f8 33 f0 d3 cf d3 ce d3 cb 3b fe 90 00 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=12
 
}