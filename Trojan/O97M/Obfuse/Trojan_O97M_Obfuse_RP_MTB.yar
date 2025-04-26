
rule Trojan_O97M_Obfuse_RP_MTB{
	meta:
		description = "Trojan:O97M/Obfuse.RP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {5e 70 2a 6f 5e 2a 77 2a 65 2a 72 2a 73 5e 5e 2a 68 2a 65 2a 6c 5e 2a 6c 2a 2a 5e 2d 2a 77 2a 69 2a 6e 2a 5e 64 2a 6f 2a 77 5e 2a 73 2a 74 2a 79 2a 5e 6c 2a 65 2a 2a 68 2a 69 2a 5e 64 2a 64 2a 5e 65 2a 6e 5e 2a 2a 2d 2a 65 2a 78 2a 5e 65 2a 63 2a 75 2a 74 2a 5e 69 2a 6f 2a 6e 2a 70 6f 6c 5e 69 63 79 2a 2a 62 2a 79 70 5e 5e 61 73 73 2a 3b 2a 24 74 65 6d 70 66 69 6c 65 2a 2a 3d 2a 2a 5b 2a 69 2a 6f 2a 2e 2a 70 2a 61 2a 74 2a 68 2a 5d 2a 3a 3a 67 65 74 74 65 6d 2a 70 66 69 6c 65 2a 6e 61 6d 65 28 29 7c 72 65 6e 5e 61 6d 65 2d 69 74 5e 65 6d 2d 6e 65 77 6e 61 6d 65 7b 24 5f 2d 72 65 70 6c 61 63 65 27 74 6d 70 24 27 2c 27 65 78 65 27 } //1 ^p*o^*w*e*r*s^^*h*e*l^*l**^-*w*i*n*^d*o*w^*s*t*y*^l*e**h*i*^d*d*^e*n^**-*e*x*^e*c*u*t*^i*o*n*pol^icy**b*yp^^ass*;*$tempfile**=**[*i*o*.*p*a*t*h*]*::gettem*pfile*name()|ren^ame-it^em-newname{$_-replace'tmp$','exe'
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_O97M_Obfuse_RP_MTB_2{
	meta:
		description = "Trojan:O97M/Obfuse.RP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {3d 20 22 50 22 3a 20 [0-07] 20 3d 20 22 6f 22 3a 20 [0-07] 20 3d 20 22 77 22 3a 20 [0-07] 20 3d 20 22 65 22 3a 20 [0-07] 20 3d 20 22 72 22 3a 20 [0-07] 20 3d 20 22 73 22 3a 20 [0-07] 20 3d 20 22 68 22 3a 20 [0-07] 20 3d 20 22 65 22 3a 20 [0-09] 20 3d 20 22 6c 22 3a 20 [0-09] 20 3d 20 22 6c 22 3a } //1
		$a_03_1 = {3d 20 22 57 22 3a 20 [0-07] 20 3d 20 22 53 22 3a 20 [0-07] 20 3d 20 22 63 22 3a 20 [0-07] 20 3d 20 22 72 22 3a 20 [0-07] 20 3d 20 22 69 22 3a 20 [0-07] 20 3d 20 22 70 22 3a 20 [0-07] 20 3d 20 22 68 22 3a 20 [0-07] 20 3d 20 22 74 22 3a 20 [0-07] 20 3d 20 22 2e 22 3a } //1
		$a_03_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-09] 29 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule Trojan_O97M_Obfuse_RP_MTB_3{
	meta:
		description = "Trojan:O97M/Obfuse.RP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2e 6f 70 65 6e 22 67 65 74 22 2c 28 22 68 3a 2f 2f 77 77 77 2e 76 6d 64 2e 6d 2f 6d 77 2f 68 64 2e 22 29 2c 66 61 6c 73 65 2e 73 65 6e 64 3d 2e 72 65 73 70 6f 6e 73 65 62 6f 64 79 69 66 2e 73 74 61 74 75 73 3d 32 30 30 74 68 65 6e 73 65 74 3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 61 64 6f 64 62 2e 73 74 72 65 61 6d 22 29 2e 6f 70 65 6e 2e 74 79 70 65 3d 2e 77 72 69 74 65 2e 73 61 76 65 74 6f 66 69 6c 65 2c 2b 2e 63 6c 6f 73 65 65 6e 64 69 66 2e 6f 70 65 6e 28 29 65 6e 64 } //1 .open"get",("h://www.vmd.m/mw/hd."),false.send=.responsebodyif.status=200thenset=createobject("adodb.stream").open.type=.write.savetofile,+.closeendif.open()end
		$a_01_1 = {73 65 74 3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 6d 69 63 72 6f 73 6f 66 74 2e 78 6d 6c 68 74 74 70 22 29 73 65 74 3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 73 68 65 6c 6c 2e 61 70 70 6c 69 63 61 74 69 6f 6e 22 29 3d } //1 set=createobject("microsoft.xmlhttp")set=createobject("shell.application")=
		$a_03_2 = {2e 73 70 65 63 69 61 6c 66 6f 6c 64 65 72 73 28 22 72 65 63 65 6e 74 22 29 64 69 6d 64 69 6d 64 69 6d 64 69 6d 64 69 6d 64 69 6d 61 73 69 6e 74 65 67 65 72 64 69 6d 64 69 6d 3d 31 72 61 6e 67 65 28 22 [0-04] 22 29 2e 76 61 6c 75 65 } //1
		$a_01_3 = {3d 63 68 72 28 35 30 29 2b 63 68 72 28 34 38 29 2b 63 68 72 28 34 38 29 } //1 =chr(50)+chr(48)+chr(48)
		$a_01_4 = {3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //1 =createobject("wscript.shell")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}