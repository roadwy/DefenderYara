
rule Ransom_Win32_LockScreen_BO{
	meta:
		description = "Ransom:Win32/LockScreen.BO,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {67 65 6d 61 } //1 gema
		$a_01_1 = {2f 67 61 74 65 2e 70 68 70 3f 68 77 69 64 3d } //1 /gate.php?hwid=
		$a_01_2 = {26 6c 6f 63 61 6c 69 70 3d } //1 &localip=
		$a_01_3 = {26 77 69 6e 76 65 72 3d } //1 &winver=
		$a_01_4 = {6e 75 52 5c 6e 6f 69 73 72 65 56 74 6e 65 72 72 75 43 5c 73 77 6f 64 6e 69 57 5c 74 66 6f 73 6f 72 63 69 4d 5c 45 52 41 57 54 46 4f 53 } //1 nuR\noisreVtnerruC\swodniW\tfosorciM\ERAWTFOS
		$a_01_5 = {73 74 6e 65 6e 6f 70 6d 6f 43 20 64 65 6c 6c 61 74 73 6e 49 5c 70 75 74 65 53 20 65 76 69 74 63 41 5c 74 66 6f 73 6f 72 63 69 4d 5c 45 52 41 57 54 46 4f 53 } //1 stnenopmoC dellatsnI\puteS evitcA\tfosorciM\ERAWTFOS
		$a_01_6 = {2f 41 63 74 69 76 65 58 00 00 ff ff ff ff 2e 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}