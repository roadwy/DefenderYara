
rule Ransom_Win32_Filecoder_SUR_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.SUR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {4b 49 4c 4c 5f 41 50 50 53 5f 45 4e 43 52 59 50 54 5f 41 47 41 49 4e } //2 KILL_APPS_ENCRYPT_AGAIN
		$a_01_1 = {38 43 38 42 38 46 38 46 2d 43 32 37 33 2d 34 30 44 35 2d 38 41 30 45 2d 30 37 43 45 33 39 42 46 41 38 42 42 } //2 8C8B8F8F-C273-40D5-8A0E-07CE39BFA8BB
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}