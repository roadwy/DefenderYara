
rule TrojanSpy_Win32_Bancos_TH_dll{
	meta:
		description = "TrojanSpy:Win32/Bancos.TH!dll,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {42 48 4f 5f 42 52 41 53 49 4c 5c 53 68 44 6f 63 56 77 45 76 65 6e 74 73 } //1 BHO_BRASIL\ShDocVwEvents
		$a_00_1 = {23 7c 23 20 53 45 4e 48 41 20 23 7c 23 20 3e 3e } //1 #|# SENHA #|# >>
		$a_00_2 = {ff ff ff ff 01 00 00 00 2a 00 00 00 } //1
		$a_00_3 = {3c 2a 69 2a 6e 2a 70 2a 75 2a 74 2a 20 2a 74 2a 79 2a 70 2a 65 2a 3d 2a 22 2a 68 2a 69 2a 64 2a 64 2a 65 2a 6e 2a 22 2a 20 2a 76 2a 61 2a 6c 2a 75 2a 65 2a 3d 2a 22 2a 6e 2a 61 2a 6f 2a 22 2a 20 2a 6e 2a 61 2a 6d 2a 65 2a } //1 <*i*n*p*u*t* *t*y*p*e*=*"*h*i*d*d*e*n*"* *v*a*l*u*e*=*"*n*a*o*"* *n*a*m*e*
		$a_02_4 = {8b 45 f4 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 74 1e 8d 45 f0 50 b9 01 00 00 00 8b d3 8b 45 fc e8 ?? ?? ?? ?? 8b 55 f0 8d 45 f8 e8 ?? ?? ?? ?? 43 4e 75 bc } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*1) >=4
 
}