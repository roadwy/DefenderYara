
rule Trojan_Win16_LionWolf_A{
	meta:
		description = "Trojan:Win16/LionWolf.A,SIGNATURE_TYPE_MACROHSTR_EXT,12 00 12 00 09 00 00 "
		
	strings :
		$a_00_0 = {6c 69 62 6b 65 72 6e 65 6c 33 32 61 6c 69 61 73 63 72 65 61 74 65 70 72 6f 63 65 73 73 61 } //5 libkernel32aliascreateprocessa
		$a_00_1 = {6c 69 62 6b 65 72 6e 65 6c 33 32 61 6c 69 61 73 63 72 65 61 74 65 72 65 6d 6f 74 65 74 68 72 65 61 64 } //5 libkernel32aliascreateremotethread
		$a_00_2 = {6c 69 62 6b 65 72 6e 65 6c 33 32 61 6c 69 61 73 76 69 72 74 75 61 6c 61 6c 6c 6f 63 65 78 } //5 libkernel32aliasvirtualallocex
		$a_00_3 = {6c 69 62 6b 65 72 6e 65 6c 33 32 61 6c 69 61 73 77 72 69 74 65 70 72 6f 63 65 73 73 6d 65 6d 6f 72 79 } //5 libkernel32aliaswriteprocessmemory
		$a_00_4 = {6e 61 6d 65 73 70 61 63 65 6e 65 74 62 69 6f 73 6e 61 6d 65 } //1 namespacenetbiosname
		$a_00_5 = {67 65 74 6f 62 6a 65 63 74 6c 64 61 70 72 6f 6f 74 64 73 65 } //1 getobjectldaprootdse
		$a_00_6 = {63 72 65 61 74 65 6f 62 6a 65 63 74 6d 73 78 6d 6c 32 64 6f 6d 64 6f 63 75 6d 65 6e 74 } //1 createobjectmsxml2domdocument
		$a_00_7 = {65 6e 76 69 72 6f 6e 77 69 6e 64 69 72 } //1 environwindir
		$a_00_8 = {65 6e 76 69 72 6f 6e 70 72 6f 67 72 61 6d 77 36 34 33 32 } //1 environprogramw6432
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*5+(#a_00_2  & 1)*5+(#a_00_3  & 1)*5+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1) >=18
 
}