
rule Trojan_BAT_StealC_AE_MTB{
	meta:
		description = "Trojan:BAT/StealC.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {06 05 07 6f ?? ?? ?? 0a 8c 29 00 00 01 28 ?? ?? ?? 0a 0a 07 17 59 0b 07 16 3c e2 ff ff ff 06 } //1
		$a_01_1 = {44 69 73 70 6c 61 63 65 6d 65 6e 74 2e 65 78 65 } //1 Displacement.exe
		$a_01_2 = {61 52 33 6e 62 66 38 64 51 70 32 66 65 4c 6d 6b 33 31 2e 6c 53 66 67 41 70 61 74 6b 64 78 73 56 63 47 63 72 6b 74 6f 46 64 2e 72 65 73 6f 75 72 63 65 73 } //1 aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}