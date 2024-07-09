
rule Trojan_Win64_Lazy_RK_MTB{
	meta:
		description = "Trojan:Win64/Lazy.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c9 49 89 43 b8 49 89 4b c0 48 8d 05 ?? ?? ?? ?? 49 89 4b d0 4d 8d 4b b8 49 89 4b d8 48 8b da 49 89 4b e0 44 8d 41 01 49 89 43 c8 89 4c 24 50 49 89 4b f0 48 8b cf } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_Lazy_RK_MTB_2{
	meta:
		description = "Trojan:Win64/Lazy.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 65 6e 61 4a 5c 44 6f 77 6e 6c 6f 61 64 73 5c 4f 73 69 72 69 73 5c 6f 75 74 70 75 74 5c 62 75 69 6c 64 5c 6f 73 69 72 69 73 2e 70 64 62 } //1 PenaJ\Downloads\Osiris\output\build\osiris.pdb
		$a_01_1 = {73 74 61 72 74 20 63 6d 64 20 2f 43 20 22 63 6f 6c 6f 72 20 62 20 26 26 20 74 69 74 6c 65 20 45 72 72 6f 72 20 26 26 20 65 63 68 6f } //1 start cmd /C "color b && title Error && echo
		$a_01_2 = {63 65 72 74 75 74 69 6c 20 2d 68 61 73 68 66 69 6c 65 20 } //1 certutil -hashfile 
		$a_01_3 = {26 26 20 74 69 6d 65 6f 75 74 20 2f 74 20 35 } //1 && timeout /t 5
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}