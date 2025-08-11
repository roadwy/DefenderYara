
rule Ransom_MSIL_TankRansom_SM_MTB{
	meta:
		description = "Ransom:MSIL/TankRansom.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_81_0 = {54 61 6e 6b 69 58 52 61 6e 73 6f 6d 77 61 72 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 TankiXRansomware.Properties.Resources.resources
		$a_81_1 = {24 63 63 65 64 62 39 38 62 2d 62 63 62 62 2d 34 61 64 62 2d 62 35 64 61 2d 61 38 30 38 36 39 38 31 63 36 65 39 } //2 $ccedb98b-bcbb-4adb-b5da-a8086981c6e9
		$a_81_2 = {54 61 6e 6b 69 58 52 61 6e 73 6f 6d 77 61 72 65 5c 6f 62 6a 5c 44 65 62 75 67 5c 54 61 6e 6b 69 58 52 61 6e 73 6f 6d 77 61 72 65 2e 70 64 62 } //2 TankiXRansomware\obj\Debug\TankiXRansomware.pdb
		$a_81_3 = {57 65 6c 63 6f 6d 65 21 20 59 6f 75 72 20 61 6c 6c 20 66 69 6c 65 73 2c 20 61 6e 64 20 64 61 74 61 20 69 73 20 46 55 4c 4c 59 20 45 4e 43 52 59 50 54 45 44 20 77 69 74 68 20 61 20 73 70 65 63 69 61 6c 20 61 6c 67 6f 72 69 74 6d 20 54 58 21 } //2 Welcome! Your all files, and data is FULLY ENCRYPTED with a special algoritm TX!
		$a_81_4 = {44 6f 6e 27 74 20 74 72 79 20 74 6f 20 6b 69 6c 6c 20 72 61 6e 73 6f 6d 77 61 72 65 20 2d 20 59 6f 75 72 20 50 43 20 77 69 6c 6c 20 62 75 72 6e } //2 Don't try to kill ransomware - Your PC will burn
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*2+(#a_81_4  & 1)*2) >=10
 
}