
rule Trojan_Win32_Lotok_AML_MTB{
	meta:
		description = "Trojan:Win32/Lotok.AML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {2b c6 8b f0 c1 e6 04 03 f3 8b d8 c1 eb 05 03 dd 33 f3 8d 1c 10 33 f3 81 c2 47 86 c8 61 2b ce 4f 75 } //3
		$a_80_1 = {46 58 4e 79 2d 53 56 67 4d 53 4c 42 30 41 74 30 2d 4f 4f 68 55 4b 73 61 2d 44 31 } //FXNy-SVgMSLB0At0-OOhUKsa-D1  1
		$a_80_2 = {7a 7a 52 54 74 46 50 39 31 2e 64 61 74 } //zzRTtFP91.dat  1
	condition:
		((#a_01_0  & 1)*3+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=5
 
}