
rule Trojan_Win64_Tedy_SGA_MTB{
	meta:
		description = "Trojan:Win64/Tedy.SGA!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 65 67 46 6c 75 73 68 4b 65 79 } //1 RegFlushKey
		$a_01_1 = {63 00 6f 00 6d 00 2e 00 65 00 6d 00 62 00 61 00 72 00 63 00 61 00 64 00 65 00 72 00 6f 00 2e 00 6c 00 73 00 61 00 73 00 73 00 65 00 } //1 com.embarcadero.lsasse
		$a_01_2 = {44 00 4c 00 4c 00 46 00 49 00 4c 00 45 00 } //1 DLLFILE
		$a_01_3 = {6c 00 6f 00 67 00 64 00 36 00 34 00 } //1 logd64
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}