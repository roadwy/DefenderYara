
rule TrojanDropper_AndroidOS_SAgnt_K_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/SAgnt.K!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {35 d9 3f 00 48 0d 04 09 90 01 04 90 01 06 0c 0e 90 01 06 0b 10 05 00 10 00 84 0f 48 0e 0e 0f b7 ed 8d dd 4f 0d 08 09 90 01 06 0b 0e 16 10 01 00 9b 0e 0e 10 90 01 06 0c 0a 90 01 06 0b 0e 90 01 04 90 01 06 0c 0d 21 dd 81 d0 05 10 00 00 31 0d 0e 10 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}