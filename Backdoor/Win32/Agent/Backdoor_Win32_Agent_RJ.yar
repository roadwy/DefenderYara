
rule Backdoor_Win32_Agent_RJ{
	meta:
		description = "Backdoor:Win32/Agent.RJ,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 37 00 07 00 00 0a 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //0a 00  SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {46 50 55 4d 61 73 6b 56 61 6c 75 65 } //05 00  FPUMaskValue
		$a_01_2 = {eb 5f 5e 5b 59 59 5d c3 ff ff ff ff 14 00 00 00 53 6f 66 74 77 61 72 65 5c 59 61 68 6f 6f 5c 70 61 67 65 72 00 00 00 00 ff ff ff ff 03 00 00 00 45 54 53 00 ff ff ff ff 0e 00 00 00 59 61 68 6f 6f 21 20 55 73 65 72 20 49 44 00 00 ff ff ff ff 0f 00 00 00 59 61 68 6f 6f b1 62 b8 b9 a1 47 0d 0a 0d 0a 00 ff ff ff ff 02 00 00 00 0d 0a 00 00 ff ff ff ff 19 00 00 00 a5 5b b1 4b b9 4c aa ba b1 4b bd 58 28 45 54 53 20 76 61 6c 75 65 29 a1 } //05 00 
		$a_01_3 = {ff ff ff ff 0b 00 00 00 59 61 68 6f 6f b1 62 b8 b9 21 21 00 ff ff ff ff 0d 00 00 00 } //0a 00 
		$a_01_4 = {55 8b ec 6a 00 6a 00 53 56 57 8b d8 33 c0 55 68 ea 78 46 00 64 ff 30 64 89 20 a1 fc 9b 46 00 8b 00 c6 40 5b 00 b2 01 a1 d4 72 42 00 e8 bb fc fb ff a3 dc af 46 00 ba 01 00 00 80 a1 dc af 46 00 e8 47 fd fb ff 33 c9 ba 00 79 46 00 a1 dc af 46 00 e8 9a fd fb ff 84 c0 0f 84 b9 01 00 00 8d 4d fc ba 20 79 46 00 a1 dc af 46 00 e8 1c ff fb ff 8b 55 fc b8 d4 af 46 00 e8 3f c8 f9 ff 8d 4d f8 ba } //0a 00 
		$a_01_5 = {f9 ff 8d 4d f8 ba 2c 79 46 00 a1 dc af 46 00 e8 fd fe fb ff 8b 55 f8 b8 d8 af 46 00 e8 20 c8 f9 ff a1 dc af 46 00 e8 b6 fc fb ff 68 44 79 46 00 ff 35 d8 af 46 00 68 5c 79 46 00 68 5c 79 46 00 68 68 79 46 00 68 5c 79 46 00 68 5c 79 46 00 ff 35 d4 af 46 00 b8 e0 af 46 00 ba 08 00 00 00 e8 09 cb f9 ff 8b 83 f8 02 00 00 8b 15 e0 af 46 00 e8 48 8b fc ff 33 c0 55 68 04 78 46 00 64 ff 30 64 } //0a 00 
		$a_01_6 = {46 00 64 ff 30 64 89 20 8b 83 fc 02 00 00 b2 01 e8 35 fc ff ff 8b 83 fc 02 00 00 ba 8c 79 46 00 8b 08 ff 91 88 00 00 00 8b 83 fc 02 00 00 ba 19 00 00 00 8b 08 ff 91 8c 00 00 00 8b 83 fc 02 00 00 83 ca ff 8b 08 ff 91 94 00 00 00 33 c0 5a 59 59 64 89 10 eb 14 } //00 00 
	condition:
		any of ($a_*)
 
}