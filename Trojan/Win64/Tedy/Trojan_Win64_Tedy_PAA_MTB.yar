
rule Trojan_Win64_Tedy_PAA_MTB{
	meta:
		description = "Trojan:Win64/Tedy.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {3d 54 5f 25 25 22 0d 0a 25 65 5a 74 4e 79 48 47 73 52 49 7a 45 50 76 6b 25 25 65 4f 70 53 4e 59 69 6e 4e 69 6f 4c 53 73 7a 25 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}