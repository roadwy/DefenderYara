
rule Ransom_MSIL_Keygroup777_PA_MTB{
	meta:
		description = "Ransom:MSIL/Keygroup777.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {52 00 65 00 61 00 64 00 6d 00 2e 00 74 00 78 00 74 00 } //1 Readm.txt
		$a_01_1 = {2e 00 4b 00 65 00 79 00 67 00 72 00 6f 00 75 00 70 00 37 00 37 00 37 00 } //1 .Keygroup777
		$a_01_2 = {59 00 6f 00 75 00 20 00 62 00 65 00 63 00 61 00 6d 00 65 00 20 00 76 00 69 00 63 00 74 00 69 00 6d 00 20 00 6f 00 66 00 20 00 74 00 68 00 65 00 20 00 6b 00 65 00 79 00 67 00 72 00 6f 00 75 00 70 00 37 00 37 00 37 00 20 00 52 00 41 00 4e 00 53 00 4f 00 4d 00 57 00 41 00 52 00 45 00 21 00 } //5 You became victim of the keygroup777 RANSOMWARE!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*5) >=7
 
}