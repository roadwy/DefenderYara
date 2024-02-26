
rule Trojan_Win64_Lazy_RA_MTB{
	meta:
		description = "Trojan:Win64/Lazy.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {62 61 72 64 67 5c 44 6f 63 75 6d 65 6e 74 73 5c 64 69 61 62 6c 6f 5c 63 6c 69 65 6e 74 5c 62 69 6e 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 63 6c 69 65 6e 74 2e 70 64 62 } //01 00  bardg\Documents\diablo\client\bin\x64\Release\client.pdb
		$a_01_1 = {61 3d 7b 7c 76 77 6a 64 64 28 66 6d 6b 6d 7b 7b 69 7a 71 28 65 67 6c } //01 00  a={|vwjdd(fmkm{{izq(egl
		$a_01_2 = {61 6a 54 53 59 52 4a 4e 61 6e 44 4e 49 2e 4a 47 4f 4c 42 41 } //00 00  ajTSYRJNanDNI.JGOLBA
	condition:
		any of ($a_*)
 
}