
rule Trojan_Win32_Zbot_AO_MTB{
	meta:
		description = "Trojan:Win32/Zbot.AO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_80_0 = {64 63 6d 73 73 65 72 76 69 63 65 73 2e 63 6f 6d } //dcmsservices.com  01 00 
		$a_80_1 = {43 3a 5c 45 30 63 4b 4e 50 4d 50 2e 65 78 65 } //C:\E0cKNPMP.exe  01 00 
		$a_80_2 = {43 3a 5c 74 61 73 6b 5c 37 34 33 36 42 33 39 43 46 39 35 34 45 31 35 42 37 34 34 32 39 32 30 33 39 31 41 31 42 41 33 33 2e 65 78 65 } //C:\task\7436B39CF954E15B7442920391A1BA33.exe  01 00 
		$a_80_3 = {43 3a 5c 55 73 65 72 73 5c 61 64 6d 69 6e 5c 44 6f 77 6e 6c 6f 61 64 73 5c 37 31 38 39 38 38 38 30 64 35 38 66 34 66 65 30 63 37 32 33 65 62 62 35 63 37 34 64 37 30 64 66 2e 76 69 72 75 73 2e 65 78 65 } //C:\Users\admin\Downloads\71898880d58f4fe0c723ebb5c74d70df.virus.exe  01 00 
		$a_80_4 = {43 3a 5c 55 73 65 72 73 5c 67 65 6f 72 67 65 5c 44 65 73 6b 74 6f 70 5c 6b 67 66 64 66 6a 64 6b 2e 65 78 65 } //C:\Users\george\Desktop\kgfdfjdk.exe  01 00 
		$a_80_5 = {43 3a 5c 55 73 65 72 73 5c 61 64 6d 69 6e 5c 44 6f 77 6e 6c 6f 61 64 73 5c 6b 67 66 64 66 6a 64 6b 2e 65 78 65 } //C:\Users\admin\Downloads\kgfdfjdk.exe  01 00 
		$a_80_6 = {43 3a 5c 55 73 65 72 73 5c 61 64 6d 69 6e 5c 44 6f 77 6e 6c 6f 61 64 73 5c 30 35 66 33 38 36 37 65 33 31 34 39 65 31 66 61 33 36 37 38 39 35 31 30 30 34 30 61 39 35 64 64 31 65 65 35 33 37 64 39 30 37 66 64 35 31 64 39 61 37 33 33 66 66 30 34 36 37 34 30 37 31 64 65 2e 65 78 65 } //C:\Users\admin\Downloads\05f3867e3149e1fa36789510040a95dd1ee537d907fd51d9a733ff04674071de.exe  00 00 
	condition:
		any of ($a_*)
 
}