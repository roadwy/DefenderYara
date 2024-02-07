
rule Trojan_Win32_Bravicae_A{
	meta:
		description = "Trojan:Win32/Bravicae.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {37 41 33 38 31 33 30 44 2d 42 45 42 37 2d 34 64 36 30 2d 42 45 37 41 2d 34 43 34 41 42 36 41 38 35 43 44 31 7d } //01 00  7A38130D-BEB7-4d60-BE7A-4C4AB6A85CD1}
		$a_01_1 = {33 38 32 33 33 38 41 35 2d 30 34 32 37 2d 30 34 31 30 2d 39 32 45 43 2d 37 34 35 41 44 34 45 31 35 37 43 41 7d } //01 00  382338A5-0427-0410-92EC-745AD4E157CA}
		$a_01_2 = {00 56 43 42 61 72 2e 44 4c 4c 00 } //01 00 
		$a_01_3 = {34 34 44 44 37 37 3b 73 63 72 6f 6c 6c 62 61 72 2d 64 61 72 6b 73 68 61 64 6f 77 2d 63 6f 6c 6f 72 3a 23 31 31 37 37 34 34 3b 73 63 72 6f 6c 6c 62 61 72 2d 73 68 61 64 6f 77 2d 63 6f 6c 6f 72 3a 23 34 34 37 37 31 31 3b 73 63 72 6f 6c 6c 62 61 72 2d 33 64 6c 69 67 68 74 2d 63 6f 6c 6f 72 3a 23 31 31 34 34 37 37 3b 7d } //01 00  44DD77;scrollbar-darkshadow-color:#117744;scrollbar-shadow-color:#447711;scrollbar-3dlight-color:#114477;}
		$a_01_4 = {6d 61 69 6c 74 6f 3a 62 61 72 40 73 6f 75 68 75 75 2e 63 6f 6d } //01 00  mailto:bar@souhuu.com
		$a_01_5 = {62 61 72 2e 73 6f 75 68 75 75 2e 63 6f 6d 2f 77 65 6c 63 6f 6d 65 2e 61 73 70 3f 69 64 3d } //00 00  bar.souhuu.com/welcome.asp?id=
	condition:
		any of ($a_*)
 
}