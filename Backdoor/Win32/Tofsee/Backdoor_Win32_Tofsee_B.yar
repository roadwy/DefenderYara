
rule Backdoor_Win32_Tofsee_B{
	meta:
		description = "Backdoor:Win32/Tofsee.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8d 85 58 ff ff ff 50 ff 75 f4 be 90 01 03 00 89 5d b0 89 5d b4 89 75 a8 89 5d ac ff 15 90 01 02 40 00 85 c0 0f 8c 90 01 01 02 00 00 53 8d 45 b0 50 56 68 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Tofsee_B_2{
	meta:
		description = "Backdoor:Win32/Tofsee.B,SIGNATURE_TYPE_PEHSTR,1e 00 1e 00 13 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 62 3a 20 73 75 62 3d 27 25 73 27 } //01 00  fb: sub='%s'
		$a_01_1 = {66 62 3a 20 73 3d 27 25 73 27 } //01 00  fb: s='%s'
		$a_01_2 = {66 62 3a 20 70 72 65 73 65 6e 63 65 3d 27 25 73 27 } //01 00  fb: presence='%s'
		$a_01_3 = {66 62 3a 20 70 3d 27 25 73 27 } //01 00  fb: p='%s'
		$a_01_4 = {66 62 3a 20 6c 75 3d 27 25 73 27 } //01 00  fb: lu='%s'
		$a_01_5 = {66 62 3a 20 66 72 3d 27 25 73 27 } //01 00  fb: fr='%s'
		$a_01_6 = {66 62 3a 20 64 61 74 72 3d 27 25 73 27 } //01 00  fb: datr='%s'
		$a_01_7 = {66 62 3a 20 78 73 3d 27 25 73 27 } //01 00  fb: xs='%s'
		$a_01_8 = {66 62 3a 20 63 5f 75 73 65 72 3d 27 25 73 27 } //01 00  fb: c_user='%s'
		$a_01_9 = {66 62 3a 20 49 45 20 66 6f 75 6e 64 } //01 00  fb: IE found
		$a_01_10 = {66 61 63 65 62 6f 6f 6b 2e 63 6f 6d } //01 00  facebook.com
		$a_01_11 = {54 57 20 25 73 20 70 65 72 72 } //01 00  TW %s perr
		$a_01_12 = {54 57 20 25 73 20 70 72 69 76 } //01 00  TW %s priv
		$a_01_13 = {54 57 20 25 73 20 72 65 63 70 } //01 00  TW %s recp
		$a_01_14 = {54 57 20 25 73 20 63 6f 6f 6b } //01 00  TW %s cook
		$a_01_15 = {54 57 20 25 73 20 6d 6f 62 69 } //01 00  TW %s mobi
		$a_01_16 = {54 57 20 25 73 20 6f 70 65 6e } //01 00  TW %s open
		$a_01_17 = {54 57 20 25 73 20 63 61 6c 6c } //01 00  TW %s call
		$a_01_18 = {2e 74 77 69 74 74 65 72 2e 63 6f 6d } //00 00  .twitter.com
		$a_01_19 = {00 78 42 00 00 01 00 01 00 01 00 00 01 00 35 02 8d 85 58 } //ff ff 
	condition:
		any of ($a_*)
 
}