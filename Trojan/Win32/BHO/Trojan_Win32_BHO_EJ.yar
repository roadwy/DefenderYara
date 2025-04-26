
rule Trojan_Win32_BHO_EJ{
	meta:
		description = "Trojan:Win32/BHO.EJ,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 63 6f 6d 2f 6f 40 73 6c 40 32 2f 6f 40 76 24 6e 5f 6f 2e 61 24 73 70 3f 64 6c 6c 3d 31 } //1 .com/o@sl@2/o@v$n_o.a$sp?dll=1
		$a_01_1 = {2e 63 6f 6d 2f 6f 40 73 6c 40 32 2f 40 65 24 78 65 2f 64 24 6e 61 6d 65 2e 68 74 40 6d 6c } //1 .com/o@sl@2/@e$xe/d$name.ht@ml
		$a_01_2 = {3f 73 65 61 72 63 68 63 6f 64 65 3d 6e 26 69 73 64 61 74 65 3d } //1 ?searchcode=n&isdate=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}