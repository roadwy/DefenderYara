
rule Trojan_Win32_AveMaria_NECV_MTB{
	meta:
		description = "Trojan:Win32/AveMaria.NECV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 8d 94 fb ff ff 03 8d a0 fb ff ff 0f be 11 8b 85 70 fb ff ff 0f be 8c 05 ac fb ff ff 33 d1 8b 85 94 fb ff ff 03 85 a0 fb ff ff 88 10 e9 76 ff ff ff } //10
		$a_01_1 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 2e 74 78 74 } //5 explorer.exe.txt
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}