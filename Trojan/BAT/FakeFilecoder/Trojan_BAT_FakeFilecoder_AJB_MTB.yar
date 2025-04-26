
rule Trojan_BAT_FakeFilecoder_AJB_MTB{
	meta:
		description = "Trojan:BAT/FakeFilecoder.AJB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {70 14 14 73 ?? ?? ?? 0a 80 01 00 00 04 7e 01 00 00 04 14 fe 06 04 00 00 06 } //2
		$a_01_1 = {52 00 65 00 6d 00 6f 00 74 00 65 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 4b 00 69 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 } //1 RemoteProcessKill.exe
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}