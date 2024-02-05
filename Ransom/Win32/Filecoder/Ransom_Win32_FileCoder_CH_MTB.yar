
rule Ransom_Win32_FileCoder_CH_MTB{
	meta:
		description = "Ransom:Win32/FileCoder.CH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_80_0 = {63 73 72 73 73 65 2e 65 78 65 } //csrsse.exe  01 00 
		$a_80_1 = {35 32 70 6f 6a 69 65 2d 44 45 43 52 59 50 54 } //52pojie-DECRYPT  01 00 
		$a_80_2 = {2e 35 32 70 6f 6a 69 65 } //.52pojie  01 00 
		$a_80_3 = {51 6b 6b 62 61 6c } //Qkkbal  01 00 
		$a_80_4 = {5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //\shell\open\command  01 00 
		$a_80_5 = {5f 45 4c 5f 48 69 64 65 4f 77 6e 65 72 } //_EL_HideOwner  01 00 
		$a_80_6 = {28 2a 2e 4a 50 47 3b 2a 2e 50 4e 47 3b 2a 2e 42 4d 50 3b 2a 2e 47 49 46 3b 2a 2e 49 43 4f 3b 2a 2e 43 55 52 29 7c 2a 2e 4a 50 47 3b 2a 2e 50 4e 47 3b 2a 2e 42 4d 50 3b 2a 2e 47 49 46 3b 2a 2e 49 43 4f 3b 2a 2e 43 55 52 7c 4a 50 47 } //(*.JPG;*.PNG;*.BMP;*.GIF;*.ICO;*.CUR)|*.JPG;*.PNG;*.BMP;*.GIF;*.ICO;*.CUR|JPG  00 00 
	condition:
		any of ($a_*)
 
}