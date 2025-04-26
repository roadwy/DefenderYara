
rule Trojan_Win32_BHO_BR{
	meta:
		description = "Trojan:Win32/BHO.BR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {45 78 70 6c 6f 72 65 72 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //1 硅汰牯牥䐮䱌䐀汬慃啮汮慯乤睯
		$a_01_1 = {3d 20 73 20 27 59 41 32 47 4f 4f 47 4c 45 27 } //1 = s 'YA2GOOGLE'
		$a_01_2 = {38 39 37 33 31 34 38 30 2d 44 34 37 44 2d 34 44 43 34 2d 38 41 33 36 2d 42 41 41 45 35 35 45 30 39 34 43 35 } //1 89731480-D47D-4DC4-8A36-BAAE55E094C5
		$a_01_3 = {45 78 70 6c 6f 72 65 72 2e 4d 45 78 70 6c 6f 72 65 72 20 3d 20 73 20 27 4d 45 78 70 6c 6f 72 65 72 20 43 6c 61 73 73 27 } //1 Explorer.MExplorer = s 'MExplorer Class'
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}