
rule Trojan_Win64_CobaltStrike_ENG_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ENG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {54 32 55 45 70 67 6f 42 46 77 36 48 58 6f 5a 38 37 46 4b 49 67 4f 71 66 72 50 79 5a 65 61 56 53 6b 34 44 49 67 4e 6d 39 56 52 50 77 37 54 53 56 45 53 62 51 7a 5a 6f 30 72 70 41 47 4a 79 68 35 54 74 59 } //1 T2UEpgoBFw6HXoZ87FKIgOqfrPyZeaVSk4DIgNm9VRPw7TSVESbQzZo0rpAGJyh5TtY
		$a_01_1 = {2f 43 50 4e 47 58 61 33 67 31 67 6d 38 68 44 33 7a 73 64 57 } //1 /CPNGXa3g1gm8hD3zsdW
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}