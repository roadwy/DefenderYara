
rule Trojan_Win32_FakeFilecoder_PA_MTB{
	meta:
		description = "Trojan:Win32/FakeFilecoder.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {53 74 72 61 77 62 65 72 72 79 20 46 69 65 6c 64 73 20 43 72 79 70 74 6f 20 4c 6f 63 6b 65 72 } //1 Strawberry Fields Crypto Locker
		$a_00_1 = {59 6f 75 72 20 69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 20 77 65 72 65 20 65 6e 63 72 79 70 74 65 64 20 6f 6e 20 74 68 69 73 20 63 6f 6d 70 75 74 65 72 } //1 Your important files were encrypted on this computer
		$a_02_2 = {54 6f 20 72 65 74 72 69 65 76 65 20 74 68 65 20 70 72 69 76 61 74 65 20 6b 65 79 2e 20 79 6f 75 20 6e 65 65 64 20 74 6f 20 70 61 79 20 [0-04] 20 62 69 74 63 6f 69 6e 73 2e } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}