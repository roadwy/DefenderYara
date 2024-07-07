
rule Ransom_Win32_Dopplepaymer_gen_C{
	meta:
		description = "Ransom:Win32/Dopplepaymer.gen!C,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {7e 00 31 00 3a 00 } //1 ~1:
		$a_01_1 = {2a 2a 2a 5f 5f 63 38 61 31 30 62 34 63 2d 30 32 39 38 2d 34 61 32 31 2d 39 64 63 31 2d 34 61 38 34 33 61 33 38 65 34 62 34 5f 5f 2a 2a 2a } //-1 ***__c8a10b4c-0298-4a21-9dc1-4a843a38e4b4__***
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*-1) >=1
 
}