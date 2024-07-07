
rule Ransom_Win32_Simlosap_A{
	meta:
		description = "Ransom:Win32/Simlosap.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_03_0 = {74 24 8d 45 90 01 01 33 d2 8a d3 83 c2 41 e8 90 01 04 8d 45 90 01 01 ba 90 01 04 e8 90 01 04 8b 45 90 01 01 e8 90 01 04 43 80 fb 1a 75 89 90 00 } //1
		$a_03_1 = {bb 05 00 00 00 e8 90 01 04 b8 1a 00 00 00 e8 90 01 04 8b d0 80 c2 41 8d 85 90 01 02 ff ff e8 90 01 04 8b 95 90 01 02 ff ff 8d 45 fc e8 90 01 04 4b 75 d0 90 00 } //1
		$a_01_2 = {61 63 63 64 62 3a 61 62 66 3a 61 33 64 3a 61 73 6d 3a 66 62 78 3a 66 62 77 3a 66 62 6b 3a 66 64 62 3a 66 62 66 3a 6d 61 78 3a 6d 33 64 3a 6c 64 66 3a 6b 65 79 73 74 6f 72 65 } //1 accdb:abf:a3d:asm:fbx:fbw:fbk:fdb:fbf:max:m3d:ldf:keystore
		$a_01_3 = {61 73 69 6d 63 6c 6f 73 65 70 61 73 73 00 } //1 獡浩汣獯灥獡s
		$a_01_4 = {70 72 69 7a 72 61 6b 7b 7d 7b 7d 7b 7d 00 } //1 牰穩慲筫筽筽}
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}