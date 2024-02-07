
rule Worm_Win32_Allaple_gen_A{
	meta:
		description = "Worm:Win32/Allaple.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3c 4f 42 4a 45 43 54 20 74 79 70 65 3d 22 61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 6f 6c 65 6f 62 6a 65 63 74 22 43 4c 41 53 53 49 44 3d 22 43 4c 53 49 44 3a 25 30 38 6c 58 2d 25 30 34 58 2d 25 30 34 58 2d 25 30 32 58 25 30 32 58 2d 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 22 3e 3c 2f 4f 42 4a 45 43 54 3e } //01 00  <OBJECT type="application/x-oleobject"CLASSID="CLSID:%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X"></OBJECT>
		$a_01_1 = {5c 6c 73 61 72 70 63 00 5c 5c 2a 53 4d 42 53 45 52 56 45 52 5c 49 50 43 24 00 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 00 70 61 73 73 77 6f 72 64 5c 5c 25 73 } //01 00  汜慳灲c屜匪䉍䕓噒剅䥜䍐$摁業楮瑳慲潴r慰獳潷摲屜猥
		$a_01_2 = {81 c4 ff ef ff ff 44 eb 02 eb 6b e8 f9 ff ff ff 53 55 56 57 8b 6c 24 18 8b 45 3c 8b 54 28 78 03 d5 8b 4a 18 8b 5a 20 03 dd e3 32 49 8b 34 8b 03 f5 33 ff fc 33 c0 ac 38 e0 74 07 } //00 00 
	condition:
		any of ($a_*)
 
}