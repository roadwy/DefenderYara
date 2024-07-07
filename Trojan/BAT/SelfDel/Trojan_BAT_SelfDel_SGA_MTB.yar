
rule Trojan_BAT_SelfDel_SGA_MTB{
	meta:
		description = "Trojan:BAT/SelfDel.SGA!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2f 00 43 00 20 00 70 00 69 00 6e 00 67 00 20 00 31 00 2e 00 31 00 2e 00 31 00 2e 00 31 00 20 00 2d 00 6e 00 20 00 32 00 20 00 2d 00 77 00 20 00 31 00 30 00 30 00 30 00 20 00 3e 00 20 00 4e 00 75 00 6c 00 20 00 26 00 20 00 44 00 65 00 6c 00 } //1 /C ping 1.1.1.1 -n 2 -w 1000 > Nul & Del
		$a_01_1 = {4b 00 6c 00 69 00 73 00 2e 00 65 00 78 00 65 00 } //1 Klis.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}