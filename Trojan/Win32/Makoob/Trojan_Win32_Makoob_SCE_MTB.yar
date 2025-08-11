
rule Trojan_Win32_Makoob_SCE_MTB{
	meta:
		description = "Trojan:Win32/Makoob.SCE!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {76 00 65 00 64 00 68 00 65 00 66 00 74 00 6e 00 69 00 6e 00 67 00 65 00 72 00 20 00 6d 00 61 00 6c 00 61 00 64 00 69 00 76 00 65 00 } //2 vedheftninger maladive
		$a_01_1 = {63 00 69 00 76 00 69 00 6c 00 69 00 73 00 65 00 72 00 20 00 73 00 70 00 69 00 6b 00 69 00 65 00 73 00 74 00 20 00 65 00 6b 00 73 00 74 00 72 00 61 00 6e 00 75 00 6d 00 6d 00 65 00 72 00 } //2 civiliser spikiest ekstranummer
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}