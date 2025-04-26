
rule TrojanDownloader_Win32_Delf_NB{
	meta:
		description = "TrojanDownloader:Win32/Delf.NB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {72 65 40 2a 2a 40 67 20 61 2a 64 64 20 22 48 4b 40 45 59 5f 43 40 2a 55 52 40 2a 52 2a 45 4e 40 54 5f 55 53 2a 45 52 } //5 re@**@g a*dd "HK@EY_C@*UR@*R*EN@T_US*ER
		$a_01_1 = {52 40 2a 23 75 2a 40 2a 6e 2a 2a 44 4c 2a 4c 33 40 23 2a 32 2e 7c 65 2a 78 40 65 2a 20 53 2a 68 65 6c 6c 2a 7c 2a 33 23 32 2e 44 2a 40 4c 2a 40 4c 2c 20 43 6f 2a 6e 74 7c 2a 72 40 2a 6f 6c 23 5f 52 40 2a 75 2a 7c 6e 2a 40 44 23 2a 4c 4c } //5 R@*#u*@*n**DL*L3@#*2.|e*x@e* S*hell*|*3#2.D*@L*@L, Co*nt|*r@*ol#_R@*u*|n*@D#*LL
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}