
rule Ransom_MSIL_TankRansom_SN_MTB{
	meta:
		description = "Ransom:MSIL/TankRansom.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_81_0 = {24 63 38 66 66 64 34 35 64 2d 63 31 33 39 2d 34 33 37 64 2d 38 31 32 38 2d 66 64 62 39 38 63 37 66 62 31 66 62 } //2 $c8ffd45d-c139-437d-8128-fdb98c7fb1fb
		$a_81_1 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 53 79 73 74 65 6d 33 32 5c 76 6f 69 63 65 2e 76 62 73 } //2 C:\Program Files\System32\voice.vbs
		$a_81_2 = {54 61 6e 6b 69 20 58 20 52 61 6e 73 6f 6d 77 61 72 65 20 32 2e 30 } //2 Tanki X Ransomware 2.0
		$a_81_3 = {59 6f 75 72 20 61 6c 6c 20 66 69 6c 65 73 20 61 6e 64 20 64 61 74 61 20 69 73 20 65 6e 63 72 79 70 74 65 64 20 62 79 20 54 61 6e 6b 69 20 58 } //2 Your all files and data is encrypted by Tanki X
		$a_81_4 = {54 61 6e 6b 69 20 58 20 52 61 6e 73 6f 6d 77 61 72 65 20 32 2e 30 5c 6f 62 6a 5c 44 65 62 75 67 5c 54 61 6e 6b 69 20 58 20 52 61 6e 73 6f 6d 77 61 72 65 20 32 2e 30 2e 70 64 62 } //2 Tanki X Ransomware 2.0\obj\Debug\Tanki X Ransomware 2.0.pdb
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*2+(#a_81_4  & 1)*2) >=10
 
}