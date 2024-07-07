
rule Trojan_Win32_Plugx_AA_MTB{
	meta:
		description = "Trojan:Win32/Plugx.AA!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {7a 32 62 71 77 37 6b 39 30 72 4a 59 41 4c 49 51 55 78 5a 4b 25 73 4f 3d 68 64 35 43 34 70 69 56 4d 46 6c 61 52 75 63 57 79 33 31 47 54 4e 48 2d 6d 45 44 38 66 6e 58 74 50 76 53 6f 6a 65 42 36 67 } //1 z2bqw7k90rJYALIQUxZK%sO=hd5C4piVMFlaRucWy31GTNH-mED8fnXtPvSojeB6g
		$a_01_1 = {53 4b 5f 50 61 72 61 73 69 74 65 } //1 SK_Parasite
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}