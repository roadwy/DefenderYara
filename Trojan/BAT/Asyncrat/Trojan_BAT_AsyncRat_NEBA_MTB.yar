
rule Trojan_BAT_AsyncRat_NEBA_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.NEBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 2c 00 00 0a 0a 06 17 6f 2d 00 00 0a 06 18 6f 2e 00 00 0a 06 03 04 6f 2f 00 00 0a 0b 07 02 16 02 8e 69 6f 30 00 00 0a 0c 07 6f 31 00 00 0a 06 6f 32 00 00 0a 08 2a } //10
		$a_01_1 = {70 61 79 6c 6f 61 64 2e 65 78 65 } //2 payload.exe
		$a_01_2 = {61 00 6d 00 73 00 69 00 2e 00 64 00 6c 00 6c 00 } //2 amsi.dll
		$a_01_3 = {56 00 69 00 72 00 74 00 75 00 61 00 6c 00 50 00 72 00 6f 00 74 00 65 00 63 00 74 00 } //2 VirtualProtect
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=16
 
}