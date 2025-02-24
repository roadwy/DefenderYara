
rule Trojan_Win64_XMRig_GA_MTB{
	meta:
		description = "Trojan:Win64/XMRig.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 65 31 42 75 37 46 55 52 6c 63 77 43 52 44 77 } //1 main.e1Bu7FURlcwCRDw
		$a_01_1 = {6d 61 69 6e 2e 55 47 4a 49 4a 31 43 75 76 33 59 44 52 } //1 main.UGJIJ1Cuv3YDR
		$a_01_2 = {6d 61 69 6e 2e 55 49 65 68 54 6f 52 49 58 62 41 47 67 77 } //1 main.UIehToRIXbAGgw
		$a_01_3 = {67 6f 3a 69 74 61 62 2e 2a 6e 65 74 2e 49 50 41 64 64 72 2c 6e 65 74 2e 41 64 64 72 } //1 go:itab.*net.IPAddr,net.Addr
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}