
rule Trojan_Win64_CobaltStrike_CCIZ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CCIZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4f 54 41 35 4d 44 6b 77 5a 6d 4d 30 4f 44 67 7a 5a 54 52 6d 4d 47 55 34 59 7a 67 77 4d 44 41 77 4d 44 41 30 4d 54 55 78 4e 44 45 31 4d 44 55 79 4e 54 } //1 OTA5MDkwZmM0ODgzZTRmMGU4YzgwMDAwMDA0MTUxNDE1MDUyNT
		$a_01_1 = {45 31 4e 6a 51 34 4d 7a 46 6b 4d 6a 59 31 4e 44 67 34 59 6a 55 79 4e 6a 41 30 4f 44 68 69 4e 54 49 78 4f 44 51 34 4f 47 49 31 4d 6a 49 77 4e 44 67 34 } //1 E1NjQ4MzFkMjY1NDg4YjUyNjA0ODhiNTIxODQ4OGI1MjIwNDg4
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}