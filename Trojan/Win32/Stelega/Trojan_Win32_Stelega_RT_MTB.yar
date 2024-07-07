
rule Trojan_Win32_Stelega_RT_MTB{
	meta:
		description = "Trojan:Win32/Stelega.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c2 83 e0 03 0f b6 80 90 01 04 30 82 90 01 04 8b 85 90 01 04 8d 80 90 01 04 03 c2 83 e0 03 0f b6 80 90 01 04 30 82 90 01 04 83 c2 06 81 fa a0 bb 0d 00 0f 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Stelega_RT_MTB_2{
	meta:
		description = "Trojan:Win32/Stelega.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {73 46 6b 44 69 40 73 40 67 40 68 48 6e 3c 71 40 6b 3c 74 3c 66 39 71 41 6b 48 65 3d 66 3a 72 } //1 sFkDi@s@g@hHn<q@k<t<f9qAkHe=f:r
		$a_81_1 = {6c 3c 74 3c 69 3d 71 42 68 3c 73 40 67 40 6a 42 72 41 6d 3c 73 39 70 3d 74 3c 68 43 6b 45 67 3e 68 47 6d } //1 l<t<i=qBh<s@g@jBrAm<s9p=t<hCkEg>hGm
		$a_81_2 = {6c 45 68 39 6a 45 65 40 72 40 71 44 65 46 6c } //1 lEh9jEe@r@qDeFl
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Stelega_RT_MTB_3{
	meta:
		description = "Trojan:Win32/Stelega.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 5d fc 31 4d 90 01 01 8b 5d 90 01 01 c7 05 90 01 04 01 00 00 00 01 1d 90 01 04 ff 0d 90 01 04 a1 90 01 04 8b 0d 90 01 04 89 08 5b 8b e5 5d 90 00 } //1
		$a_03_1 = {81 c1 8a 10 00 00 8b 55 90 01 01 8b 02 2b c1 8b 4d 90 01 01 89 01 8b 15 90 01 04 a1 90 01 04 8d 4c 10 90 01 01 89 0d 90 01 04 8b 15 90 01 04 89 15 90 01 04 a1 90 01 04 a3 90 01 04 8b 0d 90 01 04 83 c1 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}