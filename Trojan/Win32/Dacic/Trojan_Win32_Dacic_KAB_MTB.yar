
rule Trojan_Win32_Dacic_KAB_MTB{
	meta:
		description = "Trojan:Win32/Dacic.KAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_80_0 = {53 6f 66 74 77 61 72 65 5c 54 64 67 75 73 20 41 76 6f 64 77 20 50 75 62 6c 69 63 5c 54 6a 62 6f 41 70 70 } //Software\Tdgus Avodw Public\TjboApp  5
		$a_80_1 = {6c 69 62 73 6f 63 76 62 69 38 36 61 2e 64 6c 6c } //libsocvbi86a.dll  1
		$a_80_2 = {63 6f 6e 6e 63 6e 2e 69 6e 69 } //conncn.ini  1
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=7
 
}