
rule Trojan_Win32_Netwire_PC_MTB{
	meta:
		description = "Trojan:Win32/Netwire.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {83 c1 01 89 8d 90 01 02 ff ff 81 bd 90 01 02 ff ff 90 01 02 00 00 73 38 8b 85 90 01 02 ff ff 33 d2 b9 90 01 01 00 00 00 f7 f1 8b 85 90 01 02 ff ff 0f be 0c 10 8b 95 90 01 02 ff ff 0f b6 84 15 90 01 02 ff ff 33 c1 8b 8d 90 01 02 ff ff 88 84 0d 90 01 02 ff ff eb 90 09 06 00 8b 8d 90 01 02 ff ff 90 00 } //1
		$a_02_1 = {83 c0 01 89 85 90 01 02 ff ff 83 bd 90 01 02 ff ff 90 01 01 73 38 8b 85 90 01 02 ff ff 33 d2 b9 90 01 01 00 00 00 f7 f1 8b 85 90 01 02 ff ff 0f be 0c 10 8b 95 90 01 02 ff ff 0f b6 84 15 90 01 02 ff ff 33 c1 8b 8d 90 01 02 ff ff 88 84 0d 90 01 02 ff ff eb 90 09 06 00 8b 85 90 01 02 ff ff 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}