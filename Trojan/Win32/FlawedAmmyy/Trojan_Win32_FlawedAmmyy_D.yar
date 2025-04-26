
rule Trojan_Win32_FlawedAmmyy_D{
	meta:
		description = "Trojan:Win32/FlawedAmmyy.D,SIGNATURE_TYPE_PEHSTR,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 27 61 51 42 6d 41 43 67 } //1 FromBase64String('aQBmACg
		$a_01_1 = {49 6e 76 6f 6b 65 2d 45 78 70 72 65 73 73 69 6f 6e 20 2d 43 6f 6d 6d 61 6e 64 20 20 24 28 5b 73 74 72 69 6e 67 5d } //1 Invoke-Expression -Command  $([string]
		$a_01_2 = {47 51 41 66 51 41 37 41 41 30 41 43 67 41 4e 41 41 6f 41 27 29 29 29 29 } //1 GQAfQA7AA0ACgANAAoA'))))
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}