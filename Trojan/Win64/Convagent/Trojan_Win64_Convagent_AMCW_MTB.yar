
rule Trojan_Win64_Convagent_AMCW_MTB{
	meta:
		description = "Trojan:Win64/Convagent.AMCW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 6e 74 69 63 68 65 61 74 00 42 69 72 64 00 43 61 74 00 43 72 61 62 00 44 6f 67 00 44 75 63 6b 00 45 6c 65 70 68 61 6e 74 00 48 6f 70 65 00 4b 6e 69 67 68 74 00 4d 6f 6c 64 6f 76 61 00 4f 6d 61 72 00 50 65 6e 67 75 69 6e 00 57 6f 6c 66 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 44 6c 6c 4d 61 69 6e 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}